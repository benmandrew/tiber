use badge::{Badge, BadgeOptions};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
struct Report {
    data: Vec<Data>,
}

#[derive(Deserialize)]
struct Data {
    totals: Totals,
}

#[derive(Deserialize)]
struct Totals {
    lines: Metric,
}

#[derive(Deserialize)]
struct Metric {
    percent: f64,
}

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("failed to read stdin");

    let report: Report = serde_json::from_str(&input).expect("invalid coverage JSON");
    let percent = report.data[0].totals.lines.percent;

    let color = if percent >= 90.0 {
        "#4c1"
    } else if percent >= 75.0 {
        "#dfb317"
    } else {
        "#e05d44"
    };

    let badge = Badge::new(BadgeOptions {
        subject: "coverage".to_owned(),
        status: format!("{:.0}%", percent),
        color: color.to_owned(),
    })
    .expect("failed to create badge");

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has no parent dir")
        .to_owned();

    let out = root.join("doc/coverage.svg");
    std::fs::create_dir_all(out.parent().unwrap()).expect("failed to create doc dir");
    std::fs::write(&out, badge.to_svg()).expect("failed to write badge");

    eprintln!("coverage: {:.1}% → {}", percent, out.display());
}
