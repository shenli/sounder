class Sounder < Formula
  desc "Metadata-first Parquet inspector and dataset doctor"
  homepage "https://github.com/shenli/sounder"
  url "https://github.com/shenli/sounder/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "6c68db60384bf4b752da0d4b735fd9e0ed580555a4ca8a8f36b34f187a9d6706"
  license "MIT"
  head "https://github.com/shenli/sounder.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sounder version")
  end
end
