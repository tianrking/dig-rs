# Homebrew formula for dig-rs
# To install:
#   brew install tianrking/dig/dig-rs
# Or:
#   brew tap tianrking/dig
#   brew install dig-rs

class DigRs < Formula
  desc "Modern, cross-platform DNS lookup utility - dig reimagined in Rust"
  homepage "https://github.com/tianrking/dig-rs"
  url "https://github.com/tianrking/dig-rs/archive/refs/tags/v{{version}}.tar.gz"
  sha256 "{{sha256}}"

  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system bin/"dig", "example.com", "+short"
  end
end
