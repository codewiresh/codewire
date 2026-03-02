# Homebrew Formula for CodeWire
class Codewire < Formula
  desc "Persistent process server for AI coding agents"
  homepage "https://github.com/codewiresh/codewire"
  version "0.2.42"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-aarch64-apple-darwin"
      sha256 "33bc2dc55afb769ba5083b3106803c40b5392497e9cbca344d8231aa271a8822"
    else
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-x86_64-apple-darwin"
      sha256 "7e91f56f4cd7063a2f867eaed6a185cceedd46755ab6f46d61f010991fbb1c50"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-aarch64-unknown-linux-gnu"
      sha256 "1e333d33e950a64f8421aadc0ec77529a0a8d4375ec4a3fa5774419c9d6e6532"
    else
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-x86_64-unknown-linux-musl"
      sha256 "77f0a5abe55d6c8674737ca746a33dd1b127a8ad52aeaf8cfbdb7615cc7e18f3"
    end
  end

  def install
    # Determine the correct binary name based on platform
    if OS.mac?
      if Hardware::CPU.arm?
        binary_name = "cw-v#{version}-aarch64-apple-darwin"
      else
        binary_name = "cw-v#{version}-x86_64-apple-darwin"
      end
    else
      if Hardware::CPU.arm?
        binary_name = "cw-v#{version}-aarch64-unknown-linux-gnu"
      else
        binary_name = "cw-v#{version}-x86_64-unknown-linux-musl"
      end
    end

    bin.install binary_name => "cw"
    generate_completions_from_executable(bin/"cw", "completion")
  end

  test do
    # Test that the binary runs and shows help
    assert_match "Persistent process server", shell_output("#{bin}/cw --help")

    # Test version display
    system "#{bin}/cw", "--version"
  end

  def caveats
    <<~EOS
      CodeWire node will auto-start on first command.

      Quick start:
        cw launch -- claude -p "your prompt here"
        cw list
        cw attach 1

      For more information:
        https://github.com/codewiresh/codewire
    EOS
  end
end
