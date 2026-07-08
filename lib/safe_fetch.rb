# frozen_string_literal: true

require "net/http"
require "uri"
require "resolv"
require "ipaddr"

# SafeFetch downloads the body at a URL.
#
# WARNING: as shipped, this is the NAIVE / VULNERABLE version. It follows any
# scheme, any host (including internal ones), unlimited redirects, and imposes
# no size or time limits. It is the starting point for the DARE Labs lab
# "Secure a Download Endpoint Against SSRF".
#
# Complete the TODOs until spec/safe_fetch_spec.rb is green.
class SafeFetch
  # Raised when a request is refused for security reasons.
  class BlockedError < StandardError; end

  MAX_REDIRECTS = 2
  MAX_BYTES = 5 * 1024 * 1024 # 5 MiB
  TIMEOUT_SECONDS = 5

  def self.call(url)
    new.call(url)
  end

  def call(url, redirects_left = MAX_REDIRECTS)
    uri = URI.parse(url)

    # TODO (a): validate the scheme — only "https" should be allowed.
    #   Raise BlockedError for http:// and any other scheme.

    # TODO (b): resolve the host to an IP (Resolv.getaddress) and refuse to
    #   connect when it falls in a blocked range. Use private_ip? below.
    #   Remember 169.254.169.254 (cloud metadata) MUST be blocked.

    # NAIVE request: no timeout, no size cap. Replace with a guarded request.
    response = Net::HTTP.get_response(uri) # TODO (d): apply TIMEOUT_SECONDS.

    case response
    when Net::HTTPRedirection
      # TODO (c): follow at most MAX_REDIRECTS redirects, and RE-VALIDATE the
      #   new host (scheme + IP) on every hop. The naive version below follows
      #   blindly and forever.
      location = response["location"]
      return call(location, redirects_left - 1)
    else
      body = response.body.to_s

      # TODO (d): enforce MAX_BYTES — reject bodies larger than the limit
      #   (ideally while streaming, not after buffering everything).

      body
    end
  end

  private

  # Returns true when +ip+ (a String) is loopback, private, or link-local and
  # therefore must NOT be fetched.
  #
  # Blocked ranges:
  #   IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
  #         169.254.0.0/16 (includes 169.254.169.254 metadata)
  #   IPv6: ::1/128, fc00::/7, fe80::/10
  def private_ip?(ip)
    # TODO (b): implement using IPAddr, e.g.
    #   BLOCKED_RANGES.any? { |range| range.include?(IPAddr.new(ip)) }
    false
  end
end
