# Homebrew Formula for CodeWire
class Codewire < Formula
  desc "Persistent process server for AI coding agents"
  homepage "https://github.com/codewiresh/codewire"
  version "0.2.57"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-aarch64-apple-darwin"
      sha256 "e2b0fab82949c5111371ed2bfc1e899495a099ec9e8ada3ea3ab061b3abb0406"
    else
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-x86_64-apple-darwin"
      sha256 "73ad14e58b1e653bd0a9b82b1f4b089514df10ef2144463e88651cd216b16a41"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-aarch64-unknown-linux-gnu"
      sha256 "8a699a3f3185ed9b14fd292cca78e794b743ca782edd4a7e3ae614876e8d8b07"
    else
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-x86_64-unknown-linux-musl"
      sha256 "7346122cf43c36a311de9c162c6325e43730a59b64b86789da6abcde1ee12cd5"
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
