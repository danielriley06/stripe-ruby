module Stripe
  module Webhook

    # Initializes an Event object from a payload.
    #
    # This may raise JSON::ParserError if the payload is not valid JSON.
    #
    # If a signature header and secret are provided, the signatures in the
    # header will be checked and NoValidSignatureError will be raised if no
    # valid signature is found.
    def self.create_event_from_payload(payload, sig_header=nil, secret=nil)
      data = JSON.parse(payload, symbolize_names: true)
      event = Event.construct_from(data)

      unless sig_header.nil?
        raise ArgumentError, 'You must pass a secret in order to verify signatures' if secret.nil?

        unless Signature.verify_header(payload, sig_header, secret)
          raise NoValidSignatureError.new(sig_header, http_body: payload, json_body: data)
        end
      end

      event
    end

    module Signature
      # Hash mapping known signature schemes to their compute methods
      SUPPORTED_SCHEMES = {
        'v1' => :compute_hmac_sha256,
      }.freeze

      def self.compute_hmac_sha256(payload, secret)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), secret, payload)
      end

      # Splits a signature header and return a list of (scheme, signature)
      # pairs.
      def self.split_header(header)
        header.split(/,\s*/).map { |i| i.split('=', 2) }
      end

      # Returns a hash mapping each signature scheme to the expected signature
      # for the given payload and secret.
      def self.compute_expected_sigs(payload, secret)
        expected_sigs = {}
        SUPPORTED_SCHEMES.each do |scheme, method|
          expected_sigs[scheme] = send(method, payload, secret)
        end
        expected_sigs
      end

      # Verifies the signature header for a given payload.
      #
      # Returns true if the header contains at least one valid signature, false
      # otherwise.
      def self.verify_header(payload, header, secret)
        expected_sigs = compute_expected_sigs(payload, secret)

        split_header(header).each do |scheme, sig|
          next unless SUPPORTED_SCHEMES.include?(scheme)
          return true if Util.secure_compare(expected_sigs[scheme], sig)
        end

        false
      end
    end
  end
end
