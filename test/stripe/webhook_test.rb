require File.expand_path('../../test_helper', __FILE__)

module Stripe
  class WebhookTest < Test::Unit::TestCase
    EVENT_PAYLOAD = '''{
  "id": "evt_test_webhook",
  "object": "event"
}'''
    SECRET = 'hunter2'
    GOOD_SIGNATURE = 'e0dfaa7f6226043a9fae87f6763f6257da8df0e4da9756aee9054394aa103ccc'
    BAD_SIGNATURE = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'

    GOOD_HEADER = "v1=#{GOOD_SIGNATURE},v1=#{BAD_SIGNATURE},v0=#{GOOD_SIGNATURE}"
    BAD_HEADER = "v1=#{BAD_SIGNATURE},v0=#{GOOD_SIGNATURE}"

    context ".create_event_from_payload" do
      should "return an Event instance from a valid JSON payload" do
        event = Stripe::Webhook.create_event_from_payload(EVENT_PAYLOAD)
        assert event.kind_of?(Stripe::Event)
        assert_equal event.id, 'evt_test_webhook'
      end

      should "raise a JSON::ParserError from an invalid JSON payload" do
        assert_raises JSON::ParserError do
          Stripe::Webhook.create_event_from_payload("this is not valid JSON")
        end
      end

      should "return an Event instance from a valid JSON payload and valid signature header" do
        event = Stripe::Webhook.create_event_from_payload(EVENT_PAYLOAD, GOOD_HEADER, SECRET)
        assert event.kind_of?(Stripe::Event)
      end

      should "raise a NoValidSignatureError from a valid JSON payload and an invalid signature header" do
        assert_raises Stripe::NoValidSignatureError do
          Stripe::Webhook.create_event_from_payload(EVENT_PAYLOAD, BAD_HEADER, SECRET)
        end
      end
    end

    context ".verify_signature_header" do
      should "return true when the header contains a valid scheme/signature pair" do
        assert Stripe::Webhook::Signature.verify_header(EVENT_PAYLOAD, GOOD_HEADER, SECRET)
      end

      should "return false if the header contains no valid scheme/signature pair" do
        refute Stripe::Webhook::Signature.verify_header(EVENT_PAYLOAD, BAD_HEADER, SECRET)
      end
    end
  end
end
