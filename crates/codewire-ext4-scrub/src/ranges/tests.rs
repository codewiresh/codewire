//! The range parsers, from recorded e2fsprogs output.

use super::*;

#[test]
fn free_ranges_come_from_every_group_and_merge() {
    let output = b"Block count:              98304\nGroup descriptor size:    64\n\
Group 0: (Blocks 0-32767) csum 0x0bcf [ITABLE_ZEROED]\n  Free blocks: 4250-32767\n\
Group 1: (Blocks 32768-65535) csum 0x3f7e\n  Free blocks: 32768-32800, 33000, 35000-65535\n\
Group 2: (Blocks 65536-98303) csum 0x8d7a\n  Free blocks: \n";
    assert_eq!(
        free_ranges(output).unwrap(),
        [(4250, 32800), (33000, 33000), (35000, 65535)]
    );
    // A group that reports no free blocks line, a range past the end, or no
    // block count.
    assert!(free_ranges(b"Block count: 10\nGroup 0: (Blocks 0-9)\n").is_err());
    assert!(free_ranges(b"Block count: 10\nGroup 0: (Blocks 0-9)\n  Free blocks: 5-10\n").is_err());
    assert!(free_ranges(b"Group 0: (Blocks 0-9)\n  Free blocks: 5-6\n").is_err());
}

#[test]
fn stat_records_yield_unwritten_extents_and_blocks_past_the_end() {
    let mut parser = InodeBlocks::new(4096);
    for line in [
        "debugfs:  Inode: 12   Type: regular    Mode:  0666   Flags: 0x80000",
        "User:     0   Group:     0   Project:     0   Size: 8192",
        "Fragment:  Address: 0    Number: 0    Size: 0",
        "EXTENTS:",
        "(ETB0):900, (0-1):1000-1001, (2-3):1002-1003, (4-7[u]):1004-1007",
        "debugfs:  Inode: 13   Type: directory    Mode:  0700   Flags: 0x80000",
        "User:     0   Group:     0   Project:     0   Size: 4096",
        "EXTENTS:",
        "(0-3):2000-2003",
        "debugfs:  Inode: 14   Type: regular    Mode:  0600   Flags: 0x80000",
        "User:  1000   Group:  1000   Project:     0   Size: 1",
        "EXTENTS:",
        "(0):3000",
    ] {
        parser.line(line);
    }
    assert_eq!(
        parser.finish(&[12, 13, 14]).unwrap(),
        [(1002, 1003), (1004, 1007)]
    );
    assert_eq!(
        parse_extent("(5[u]):70"),
        Some(Some(FileExtent {
            logical: 5,
            physical: 70,
            length: 1,
            unwritten: true
        }))
    );
    assert_eq!(parse_extent("(0-3):10-11"), None);
    let mut broken = InodeBlocks::new(4096);
    broken.line("Inode: 12   Type: regular");
    broken.line("User: 0 Size: x");
    assert!(broken.finish(&[12]).is_err());
}

#[test]
fn a_verity_files_merkle_tree_starts_at_its_size_rounded_up_to_64_kib() {
    let mut parser = InodeBlocks::new(4096);
    for line in [
        "debugfs:  Inode: 12   Type: regular    Mode:  0444   Flags: 0x180000",
        "User:     0   Group:     0   Project:     0   Size: 8192",
        "EXTENTS:",
        "(0-1):1000-1001, (2-3):1002-1003, (4-7[u]):1004-1007, (16-18):1016-1018",
        "debugfs:  Inode: 13   Type: regular    Mode:  0444   Flags: 0x180000",
        "User:     0   Group:     0   Project:     0   Size: 65537",
        "EXTENTS:",
        "(0[u]):2000, (1-17):2001-2017, (31-33):2031-2033",
    ] {
        parser.line(line);
    }
    // The tree starts at block 16 of the first file and 32 of the second.
    // Every unwritten extent, and every block past the end before the tree,
    // still goes.
    assert_eq!(
        parser.finish(&[12, 13]).unwrap(),
        [
            (1002, 1003),
            (1004, 1007),
            (2000, 2000),
            (2017, 2017),
            (2031, 2031)
        ]
    );
    // An inode line must say its flags.
    let mut flagless = InodeBlocks::new(4096);
    flagless.line("debugfs:  Inode: 12   Type: regular    Mode:  0444");
    flagless.line("User:     0   Group:     0   Project:     0   Size: 0");
    assert!(flagless.finish(&[12]).is_err());
}

#[test]
fn stat_records_must_answer_each_inode_once_and_say_a_files_size() {
    let record = |inode: u64| {
        [
            format!("debugfs:  Inode: {inode}   Type: regular    Mode:  0600   Flags: 0x80000"),
            "User:     0   Group:     0   Project:     0   Size: 4096".to_owned(),
            "EXTENTS:".to_owned(),
            format!("(0):{}", 1000 + inode),
        ]
    };
    let parse = |inodes: &[u64], requested: &[u64]| {
        let mut parser = InodeBlocks::new(4096);
        for inode in inodes {
            for line in record(*inode) {
                parser.line(&line);
            }
        }
        parser.finish(requested)
    };
    assert!(parse(&[12, 13], &[12, 13]).unwrap().is_empty());
    // A record missing, repeated, extra or out of order.
    assert!(parse(&[12], &[12, 13]).is_err());
    assert!(parse(&[12, 12, 13], &[12, 13]).is_err());
    assert!(parse(&[12, 13, 14], &[12, 13]).is_err());
    assert!(parse(&[13, 12], &[12, 13]).is_err());
    // A regular file's record without its `User:` line.
    let mut sizeless = InodeBlocks::new(4096);
    sizeless.line("debugfs:  Inode: 12   Type: regular    Mode:  0600   Flags: 0x80000");
    sizeless.line("EXTENTS:");
    sizeless.line("(0):1000");
    assert!(sizeless.finish(&[12]).is_err());
    // A directory without one is not a file the guest reads past.
    let mut directory = InodeBlocks::new(4096);
    directory.line("debugfs:  Inode: 12   Type: directory    Mode:  0700   Flags: 0x80000");
    assert!(directory.finish(&[12]).unwrap().is_empty());
}

#[test]
fn indirect_block_maps_yield_their_blocks_past_the_end() {
    let mut parser = InodeBlocks::new(4096);
    for line in [
        "debugfs:  Inode: 13   Type: regular    Mode:  0600   Flags: 0x0",
        "User:     0   Group:     0   Project:     0   Size: 5000",
        "BLOCKS:",
        "(0-11):2095-2106, (IND):2107, (12-1035):2108-3131, (DIND):3132, (IND):3133, (1036-1220):3134-3318",
        "TOTAL: 1224",
    ] {
        parser.line(line);
    }
    // Size 5000 is two blocks: everything from logical block 2 on.
    assert_eq!(
        merge_ranges(parser.finish(&[13]).unwrap()),
        [(2097, 2106), (2108, 3131), (3134, 3318)]
    );
    assert_eq!(parse_extent("(TIND):77"), Some(None));
    assert_eq!(parse_extent("(XIND):77"), None);
}

#[test]
fn used_inodes_are_every_group_minus_its_free_ones() {
    let output = b"Inode count:              32\nInodes per group:         16\nFirst inode:              11\n\
Group 0: (Blocks 0-32767)\n  Free inodes: 14-16\n\
Group 1: (Blocks 32768-65535)\n  Free inodes: 17-20, 23-32\n";
    assert_eq!(used_inodes(output).unwrap(), [11, 12, 13, 21, 22]);
    assert!(used_inodes(b"Inode count: 32\nInodes per group: 16\nFirst inode: 11\nGroup 0: (Blocks 0-9)\n  Free inodes: 14-16\n").is_err());
    assert!(used_inodes(b"Inode count: 16\nInodes per group: 16\nFirst inode: 11\nGroup 0: (Blocks 0-9)\n  Free inodes: 14-40\n").is_err());
}
