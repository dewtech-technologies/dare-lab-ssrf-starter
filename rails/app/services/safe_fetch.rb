require "net/http"
require "uri"
require "resolv"
require "ipaddr"

# SafeFetch downloads a remote file for the POST /downloads endpoint.
#
# =========================== THIS IS THE LAB ================================
# Right now this fetcher is NAIVE: it follows ANY url it is given. That makes
# it a textbook SSRF sink — an attacker can point `file_url` at internal hosts,
# the cloud metadata endpoint (169.254.169.254), localhost admin panels, etc.
#
# Your job: harden this service so the security specs in
# spec/requests/downloads_spec.rb go green, WITHOUT breaking the happy path.
# Look for the TODOs below. Do NOT weaken the tests.
# ===========================================================================
class SafeFetch
  # Raised whenever a URL is rejected as unsafe. The controller turns this
  # into a 422 response.
  class Error < StandardError; end

  MAX_REDIRECTS = 2
  MAX_BYTES     = 5 * 1024 * 1024 # 5 MB
  OPEN_TIMEOUT  = 5
  READ_TIMEOUT  = 5

  Result = Struct.new(:body, :final_url)

  def self.call(raw_url)
    new(raw_url).call
  end

  def initialize(raw_url)
    @raw_url = raw_url.to_s
  end

  def call
    url = @raw_url

    MAX_REDIRECTS.succ.times do
      uri = URI.parse(url)

      # TODO(1): reject anything that is not https://. Right now http:// (and
      #          even file://, gopher://, ...) sail straight through.

      # TODO(2): resolve the hostname to its IP address(es) with
      #          Resolv.getaddresses(uri.host) and reject if ANY resolved
      #          address is private/loopback/link-local (see private_ip?
      #          below). This is what stops DNS pointing a public-looking host
      #          at 127.0.0.1 or 169.254.169.254.

      response = fetch(uri)

      case response
      when Net::HTTPRedirection
        # TODO(3): only allow up to MAX_REDIRECTS hops AND re-run the https +
        #          private-IP checks on the redirect target (below) — an
        #          allowed host can 302 you straight into the metadata service.
        url = response["location"]
        next
      when Net::HTTPSuccess
        # TODO(4): enforce MAX_BYTES. Today we happily read the whole body into
        #          memory no matter how large it is.
        return Result.new(response.body, uri.to_s)
      else
        raise Error, "unexpected response: #{response.code}"
      end
    end

    raise Error, "too many redirects"
  end

  private

  # Performs the actual HTTP request. Timeouts are wired up; the body is read
  # in full (see TODO(4) about capping it).
  def fetch(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.open_timeout = OPEN_TIMEOUT
    http.read_timeout = READ_TIMEOUT
    http.request(Net::HTTP::Get.new(uri))
  end

  # Returns true when `ip` (a string) is in a range that must never be reached
  # from a user-supplied URL: loopback, private, link-local (incl. the cloud
  # metadata address 169.254.169.254) and their IPv6 equivalents.
  #
  # TODO(5): implement this. Suggested ranges:
  #   IPv4  127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  #         169.254.0.0/16
  #   IPv6  ::1/128, fc00::/7, fe80::/10
  # Hint: IPAddr.new("10.0.0.0/8").include?(IPAddr.new(ip)).
  def private_ip?(ip)
    false # naive: nothing is considered private yet
  end
end
