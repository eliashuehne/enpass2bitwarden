class Enpass2bitwarden < Formula
  desc "Migrate an Enpass v6 vault to Bitwarden/Vaultwarden (passkeys + attachments included)"
  homepage "https://github.com/eliashuehne/enpass2bitwarden"
  version "1.1.1"
  license "MIT"

  livecheck do
    url :stable
    strategy :github_latest
  end

  if OS.mac?
    url "https://github.com/eliashuehne/enpass2bitwarden/releases/download/v#{version}/enpass2bitwarden-darwin-arm64"
    sha256 "b84c9d9f36c2af7d3608afe361d863ba5d8361864456606b86f07973b54cef2f"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/eliashuehne/enpass2bitwarden/releases/download/v#{version}/enpass2bitwarden-linux-amd64"
    sha256 "a3c3c3fddc0d313110d6cef4860152f169e9cf6efa636fde95abbc52b8a9eebd"
  elsif OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/eliashuehne/enpass2bitwarden/releases/download/v#{version}/enpass2bitwarden-linux-arm64"
    sha256 "cbd141758257569abd073e007e3d7056aa55e239ddd13fe149b6d097e5bbe859"
  end

  def install
    bin.install Dir["enpass2bitwarden-*"].first => "enpass2bitwarden"
  end

  def caveats
    <<~EOS
      You also need the Bitwarden CLI:
        brew install bitwarden-cli
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/enpass2bitwarden --version")
  end
end
