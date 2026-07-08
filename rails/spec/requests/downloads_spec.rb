require "rails_helper"

# These specs describe the SECURE behaviour we want. In the starter state the
# naive SafeFetch does none of the blocking, so every security example fails
# cleanly (it returns 200 where we demand 422). Harden app/services/safe_fetch.rb
# until they pass. The happy-path example already passes.
RSpec.describe "POST /downloads", type: :request do
  # Pretend `host` resolves (via DNS) to the given IP addresses. The secure
  # SafeFetch is expected to call Resolv.getaddresses(host) and reject the URL
  # when any address is private/loopback/link-local.
  def stub_dns(host, *ips)
    allow(Resolv).to receive(:getaddresses).with(host).and_return(ips)
  end

  def post_download(url)
    post "/downloads", params: { file_url: url }
  end

  it "downloads a small file from a public host (happy path)" do
    stub_dns("files.example.com", "93.184.216.34")
    stub_request(:get, "https://files.example.com/report.pdf")
      .to_return(status: 200, body: "hello world")

    post_download("https://files.example.com/report.pdf")

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body["ok"]).to be(true)
  end

  it "rejects a plain http:// url" do
    stub_request(:get, "http://files.example.com/report.pdf")
      .to_return(status: 200, body: "hello world")

    post_download("http://files.example.com/report.pdf")

    expect(response).to have_http_status(:unprocessable_entity)
  end

  it "rejects a host that resolves to loopback (127.0.0.1)" do
    stub_dns("evil.example.com", "127.0.0.1")
    stub_request(:get, "https://evil.example.com/x").to_return(status: 200, body: "x")

    post_download("https://evil.example.com/x")

    expect(response).to have_http_status(:unprocessable_entity)
  end

  it "rejects a host that resolves to a private range (10.0.0.5)" do
    stub_dns("evil.example.com", "10.0.0.5")
    stub_request(:get, "https://evil.example.com/x").to_return(status: 200, body: "x")

    post_download("https://evil.example.com/x")

    expect(response).to have_http_status(:unprocessable_entity)
  end

  it "rejects the cloud metadata address (169.254.169.254)" do
    stub_dns("evil.example.com", "169.254.169.254")
    stub_request(:get, "https://evil.example.com/latest/meta-data/")
      .to_return(status: 200, body: "creds")

    post_download("https://evil.example.com/latest/meta-data/")

    expect(response).to have_http_status(:unprocessable_entity)
  end

  it "rejects a redirect that points at a private host" do
    stub_dns("safe.example.com", "93.184.216.34")
    stub_dns("internal.example.com", "10.0.0.5")
    stub_request(:get, "https://safe.example.com/start")
      .to_return(status: 302, headers: { "Location" => "https://internal.example.com/secret" })
    stub_request(:get, "https://internal.example.com/secret")
      .to_return(status: 200, body: "secret")

    post_download("https://safe.example.com/start")

    expect(response).to have_http_status(:unprocessable_entity)
  end

  it "rejects a file that exceeds the size limit" do
    stub_dns("files.example.com", "93.184.216.34")
    big_body = "a" * (SafeFetch::MAX_BYTES + 1)
    stub_request(:get, "https://files.example.com/big.bin")
      .to_return(status: 200, body: big_body)

    post_download("https://files.example.com/big.bin")

    expect(response).to have_http_status(:unprocessable_entity)
  end
end
