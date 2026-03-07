# Homebrew Formula for CodeWire
class Codewire < Formula
  desc "Persistent process server for AI coding agents"
  homepage "https://github.com/codewiresh/codewire"
  version "0.2.52"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-aarch64-apple-darwin"
      sha256 "92365edd0b146293a8165bba3ed7dd08b4da8dd53a4456c0cc4199fafb04c29e"
    else
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-x86_64-apple-darwin"
      sha256 "69614eb7b5117f98254f050809da88e76b8ad08162686253c12fd28d6e0fd575"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-aarch64-unknown-linux-gnu"
      sha256 "9ecafe72163b3251ea08bf15f1c47ddec827136e12183c2e8b5b6fe120170bd7"
    else
      url "https://github.com/codewiresh/codewire/releases/download/v#{version}/cw-v#{version}-x86_64-unknown-linux-musl"
      sha256 "ddb48cf8e973d7112cc1a6e4c76424c6d12f8bd984feb94ada33b6dfb89d2745"
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
