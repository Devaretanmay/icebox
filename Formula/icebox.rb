class Icebox < Formula
  desc "Runtime governance for autonomous offensive security"
  homepage "https://github.com/Devaretanmay/icebox"
  url "https://github.com/Devaretanmay/icebox/archive/refs/tags/v0.2.6.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/icebox-daemon", "--version"
  end
end
