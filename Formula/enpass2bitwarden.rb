class Enpass2bitwarden < Formula
  desc "Migrate an Enpass v6 vault to Bitwarden/Vaultwarden (passkeys + attachments included)"
  homepage "https://github.com/eliashuehne/enpass2bitwarden"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/eliashuehne/enpass2bitwarden/releases/download/v1.0.0/enpass2bitwarden-darwin-arm64"
      sha256 "c1922d1133c9957d7121b6d652aa7c8d29a76be82cd32b9ac82813004e08bb92"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/eliashuehne/enpass2bitwarden/releases/download/v1.0.0/enpass2bitwarden-linux-amd64"
      sha256 "f92d7d2d458af762ae7e7f63dcf7c7b9500dcfeb548e5cd07f7e0fadc53dccb8"
    elsif Hardware::CPU.arm? && !Hardware::CPU.is_64_bit?
      raise UnsupportedArchitectureException.new("arm32 not supported")
    else
      url "https://github.com/eliashuehne/enpass2bitwarden/releases/download/v1.0.0/enpass2bitwarden-linux-arm64"
      sha256 "d6fe25bd54407bcfe56390186b546f852f4c937e7824cd74e23da3efc970f34b"
    end
  end

  def install
    bin.install "enpass2bitwarden-darwin-arm64" => "enpass2bitwarden" if OS.mac?
    bin.install "enpass2bitwarden-linux-amd64" => "enpass2bitwarden" if OS.linux? && Hardware::CPU.intel?
    bin.install "enpass2bitwarden-linux-arm64" => "enpass2bitwarden" if OS.linux? && Hardware::CPU.arm?
  end

  def caveats
    <<~EOS
      Requires the Bitwarden CLI ('bw') for the import and attach steps:
        brew install bitwarden-cli
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/enpass2bitwarden --version")
  end
end
