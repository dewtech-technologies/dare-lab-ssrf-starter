# frozen_string_literal: true

require "spec_helper"
require "resolv"

RSpec.describe SafeFetch do
  # Force DNS resolution of +host+ to a fixed +ip+ so the security checks are
  # deterministic and no real DNS is used.
  def stub_dns(host, ip)
    allow(Resolv).to receive(:getaddress).with(host).and_return(ip)
  end

  describe "scheme validation" do
    it "rejects http:// (only https is allowed)" do
      stub_dns("example.com", "93.184.216.34")

      expect { described_class.call("http://example.com/file.txt") }
        .to raise_error(SafeFetch::BlockedError)
    end
  end

  describe "blocked IP ranges (SSRF)" do
    it "rejects a host that resolves to loopback 127.0.0.1" do
      stub_dns("evil.test", "127.0.0.1")

      expect { described_class.call("https://evil.test/file.txt") }
        .to raise_error(SafeFetch::BlockedError)
    end

    it "rejects a host that resolves to private 10.0.0.5" do
      stub_dns("evil.test", "10.0.0.5")

      expect { described_class.call("https://evil.test/file.txt") }
        .to raise_error(SafeFetch::BlockedError)
    end

    it "rejects the cloud metadata address 169.254.169.254" do
      stub_dns("evil.test", "169.254.169.254")

      expect { described_class.call("https://evil.test/latest/meta-data/") }
        .to raise_error(SafeFetch::BlockedError)
    end
  end

  describe "redirects" do
    it "rejects a redirect that points at a private host" do
      stub_dns("public.test", "93.184.216.34")
      stub_dns("internal.test", "10.0.0.5")

      stub_request(:get, "https://public.test/file.txt")
        .to_return(status: 302, headers: { "Location" => "https://internal.test/secret" })

      expect { described_class.call("https://public.test/file.txt") }
        .to raise_error(SafeFetch::BlockedError)
    end
  end

  describe "size limit" do
    it "rejects a file larger than the maximum size" do
      stub_dns("public.test", "93.184.216.34")

      oversized = "A" * (SafeFetch::MAX_BYTES + 1)
      stub_request(:get, "https://public.test/big.bin")
        .to_return(status: 200, body: oversized,
                   headers: { "Content-Length" => oversized.bytesize.to_s })

      expect { described_class.call("https://public.test/big.bin") }
        .to raise_error(SafeFetch::BlockedError)
    end
  end

  describe "happy path" do
    it "downloads a small file from a public host" do
      stub_dns("public.test", "93.184.216.34")

      stub_request(:get, "https://public.test/hello.txt")
        .to_return(status: 200, body: "hello world")

      expect(described_class.call("https://public.test/hello.txt"))
        .to eq("hello world")
    end
  end
end
