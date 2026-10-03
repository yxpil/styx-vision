//! 解码器注入 / 鲁棒性测试。
//!
//! 真实用户上传的"图片字节"是不可信输入。这里喂给手写 PNG/BMP/JPEG 解码器
//! 一堆畸形、截断、伪造头的字节，断言：
//! 1. 绝不 panic（没有越界读 / 整数溢出 / 巨量分配）；
//! 2. 要么 `decoded=false` 安全降级，要么返回 `Err`；
//! 3. `analyze` 永远产出一段描述字符串。

use styx_vision::{analyze, decode, dimensions, sniff};

/// 一组"什么都不是"的字节。
fn adversarial_payloads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", vec![]),
        ("nul", vec![0u8; 64]),
        ("ff", vec![0xffu8; 64]),
        ("random_text", b"<html><script>alert(1)</script></html>".to_vec()),
        ("sql_in_text", b"'); DROP TABLE images;--".to_vec()),
        ("png_magic_truncated", vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
        ("jpeg_magic_truncated", vec![0xFF, 0xD8, 0xFF, 0xE0]),
        ("bmp_magic_truncated", b"BM".to_vec()),
    ]
}

#[test]
fn malformed_bytes_never_panic_and_safely_degrade() {
    for (name, bytes) in adversarial_payloads() {
        // analyze 永不 panic，且一定产出描述
        let facts = analyze(&bytes);
        let desc = facts.describe();
        assert!(!desc.is_empty(), "{name}: describe 应为空串");
        // 这些都不是真图 → 没解出像素，不能谎称看见内容
        assert!(!facts.decoded, "{name}: 畸形字节不该被当成真图");

        // decode 要么 Err 要么安全返回，绝不 panic
        match decode(&bytes) {
            Ok(bmp) => assert!(bmp.pixels.is_empty() || facts.decoded, "{name}"),
            Err(_) => {} // 正常：认不出/损坏
        }
        // dimensions / sniff 也只是返回 Option，绝不 panic
        let _ = dimensions(&bytes);
        let _ = sniff(&bytes);
    }
}

/// 伪造 PNG IHDR：声声明称一个荒谬巨大的尺寸。
/// 解码器绝不能据此去分配几 GB 的像素缓冲，也不能溢出 panic。
#[test]
fn png_claiming_huge_dimensions_is_rejected_not_ooms() {
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    // IHDR length=13 + "IHDR" + 13 字节头：宽=0x7fff_ffff 高=0x7fff_ffff
    png.extend_from_slice(&13u32.to_be_bytes());
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&0x7fff_ffffu32.to_be_bytes()); // width
    png.extend_from_slice(&0x7fff_ffffu32.to_be_bytes()); // height
    png.extend_from_slice(&[8, 2, 0, 0, 0]); // bitdepth/color/...
    png.extend_from_slice(&0u32.to_be_bytes()); // crc（假的，无所谓）

    // 两种入口都不能 panic
    let facts = analyze(&png);
    assert!(!facts.decoded, "巨尺寸 PNG 不得被当成真图");
    assert!(analyze(&png).describe().len() < 4096);
    match decode(&png) {
        Ok(_) => panic!("荒谬尺寸必须被拒绝"),
        Err(_) => {} // 正确：拒绝
    }
}

#[test]
fn negative_or_zero_dimensions_in_bmp_header_are_safe() {
    // BMP 头里塞负宽/高/0 宽：解码器不得越界或 panic。
    let mut bmp = b"BM".to_vec();
    // 伪造 54 字节头，宽=-1, 高=-1（i32 补码）
    bmp.extend_from_slice(&[0u8; 12]);
    bmp.extend_from_slice(&(-1i32).to_le_bytes()); // width
    bmp.extend_from_slice(&(-1i32).to_le_bytes()); // height
    bmp.extend_from_slice(&[0u8; 20]);

    let facts = analyze(&bmp);
    assert!(!facts.decoded);
    let _ = decode(&bmp);
}

#[test]
fn path_traversal_or_shell_metachars_in_bytes_are_treated_as_opaque_data() {
    // 字节里塞路径穿越 / shell 元字符：它们只是被解码的像素数据，
    // 绝不被解释成路径或命令——这里只断言分析照常进行、不 panic。
    let evil = b"../../etc/passwd";
    let facts = analyze(evil);
    assert!(!facts.decoded);
    assert!(!facts.describe().contains("passwd"), "路径串不得泄漏进描述");

    let evil2 = b"x; rm -rf / #";
    let facts2 = analyze(evil2);
    assert!(!facts2.decoded);
}
