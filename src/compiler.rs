use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use inkwell::context::Context as LlvmContext;
use inkwell::targets::*;
use inkwell::AddressSpace;
use inkwell::IntPredicate;
use inkwell::OptimizationLevel;

// TC actions
const TC_ACT_OK: u64 = 0;
const TC_ACT_SHOT: u64 = 2;

// struct __sk_buff field offsets (UAPI stable)
const SKB_DATA_OFFSET: u64 = 76;
const SKB_DATA_END_OFFSET: u64 = 80;

// Ethernet header
const ETH_HEADER_LEN: u64 = 14;
const ETH_TYPE_OFFSET: u64 = 12;
const ETH_TYPE_IPV4_LE: u64 = 0x0008; // 0x0800 in network byte order, as LE u16

// IPv4 header
const IPV4_SRC_OFFSET: u64 = ETH_HEADER_LEN + 12; // 26
const IPV4_MIN_PACKET_LEN: u64 = ETH_HEADER_LEN + 20; // 34

pub fn compile_filter(allowed_ips: &[Ipv4Addr]) -> Result<Vec<u8>> {
    let context = LlvmContext::create();
    let module = context.create_module("vm_filter");
    let builder = context.create_builder();

    let i8_type = context.i8_type();
    let i16_type = context.i16_type();
    let i32_type = context.i32_type();
    let i64_type = context.i64_type();
    let ptr_type = context.ptr_type(AddressSpace::default());

    let fn_type = i32_type.fn_type(&[ptr_type.into()], false);
    let function = module.add_function("vm_filter", fn_type, None);
    function.set_section(Some("classifier"));

    let entry = context.append_basic_block(function, "entry");
    let bounds_check = context.append_basic_block(function, "bounds_check");
    let check_eth = context.append_basic_block(function, "check_eth");
    let check_ip = context.append_basic_block(function, "check_ip");
    let allow_block = context.append_basic_block(function, "allow");
    let deny_block = context.append_basic_block(function, "deny");

    builder.position_at_end(entry);
    let skb = function.get_nth_param(0).unwrap().into_pointer_value();

    let data = {
        let field = unsafe {
            builder
                .build_gep(
                    i8_type,
                    skb,
                    &[i64_type.const_int(SKB_DATA_OFFSET, false)],
                    "data_ptr",
                )
                .unwrap()
        };
        let val = builder
            .build_load(i32_type, field, "data_u32")
            .unwrap()
            .into_int_value();
        let val64 = builder
            .build_int_z_extend(val, i64_type, "data_u64")
            .unwrap();
        builder.build_int_to_ptr(val64, ptr_type, "data").unwrap()
    };

    let data_end = {
        let field = unsafe {
            builder
                .build_gep(
                    i8_type,
                    skb,
                    &[i64_type.const_int(SKB_DATA_END_OFFSET, false)],
                    "end_ptr",
                )
                .unwrap()
        };
        let val = builder
            .build_load(i32_type, field, "end_u32")
            .unwrap()
            .into_int_value();
        let val64 = builder
            .build_int_z_extend(val, i64_type, "end_u64")
            .unwrap();
        builder
            .build_int_to_ptr(val64, ptr_type, "data_end")
            .unwrap()
    };

    builder.build_unconditional_branch(bounds_check).unwrap();

    builder.position_at_end(bounds_check);
    let data_plus = unsafe {
        builder
            .build_gep(
                i8_type,
                data,
                &[i64_type.const_int(IPV4_MIN_PACKET_LEN, false)],
                "data_plus",
            )
            .unwrap()
    };
    let lhs = builder
        .build_ptr_to_int(data_plus, i64_type, "lhs")
        .unwrap();
    let rhs = builder.build_ptr_to_int(data_end, i64_type, "rhs").unwrap();
    let in_bounds = builder
        .build_int_compare(IntPredicate::ULE, lhs, rhs, "in_bounds")
        .unwrap();
    builder
        .build_conditional_branch(in_bounds, check_eth, allow_block)
        .unwrap();

    builder.position_at_end(check_eth);
    let ethtype_ptr = unsafe {
        builder
            .build_gep(
                i8_type,
                data,
                &[i64_type.const_int(ETH_TYPE_OFFSET, false)],
                "ethtype_ptr",
            )
            .unwrap()
    };
    let ethtype = builder
        .build_load(i16_type, ethtype_ptr, "ethtype")
        .unwrap()
        .into_int_value();
    let is_ipv4 = builder
        .build_int_compare(
            IntPredicate::EQ,
            ethtype,
            i16_type.const_int(ETH_TYPE_IPV4_LE, false),
            "is_ipv4",
        )
        .unwrap();
    builder
        .build_conditional_branch(is_ipv4, check_ip, allow_block)
        .unwrap();

    builder.position_at_end(check_ip);
    let src_ip_ptr = unsafe {
        builder
            .build_gep(
                i8_type,
                data,
                &[i64_type.const_int(IPV4_SRC_OFFSET, false)],
                "src_ip_ptr",
            )
            .unwrap()
    };
    let src_ip = builder
        .build_load(i32_type, src_ip_ptr, "src_ip")
        .unwrap()
        .into_int_value();

    let cases: Vec<_> = allowed_ips
        .iter()
        .map(|ip| {
            let raw = u32::from_ne_bytes(ip.octets());
            (i32_type.const_int(raw as u64, false), allow_block)
        })
        .collect();
    builder.build_switch(src_ip, deny_block, &cases).unwrap();

    builder.position_at_end(allow_block);
    builder
        .build_return(Some(&i32_type.const_int(TC_ACT_OK, false)))
        .unwrap();
    builder.position_at_end(deny_block);
    builder
        .build_return(Some(&i32_type.const_int(TC_ACT_SHOT, false)))
        .unwrap();

    emit_bpf_elf(&module)
}

fn emit_bpf_elf(module: &inkwell::module::Module) -> Result<Vec<u8>> {
    Target::initialize_bpf(&InitializationConfig::default());

    let triple = TargetTriple::create("bpfel-unknown-none");
    let target = Target::from_triple(&triple).unwrap();
    let machine = target
        .create_target_machine(
            &triple,
            "",
            "",
            OptimizationLevel::Aggressive,
            RelocMode::Default,
            CodeModel::Default,
        )
        .context("failed to create target machine")?;

    eprintln!("LLVM IR:");
    module.print_to_stderr();

    let buf = machine
        .write_to_memory_buffer(module, FileType::Object)
        .map_err(|e| anyhow::anyhow!("codegen failed: {}", e))?;

    Ok(buf.as_slice().to_vec())
}
