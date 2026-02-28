# frozen_string_literal: true

require "test_helper"
require "tempfile"
require "hexapdf"

class PdfFileSignableTest < EasyCodeSignTest
  def setup
    @temp_pdf = Tempfile.new(["test", ".pdf"])
    create_test_pdf(@temp_pdf.path)
  end

  def teardown
    @temp_pdf.close
    @temp_pdf.unlink
  end

  def test_validates_pdf_extension
    txt_file = Tempfile.new(["test", ".txt"])
    txt_file.write("content")
    txt_file.close

    assert_raises(EasyCodeSign::InvalidPdfError) do
      EasyCodeSign::Signable::PdfFile.new(txt_file.path)
    end
  ensure
    txt_file.unlink
  end

  def test_validates_pdf_header
    fake_pdf = Tempfile.new(["fake", ".pdf"])
    fake_pdf.write("Not a PDF file")
    fake_pdf.close

    assert_raises(EasyCodeSign::InvalidPdfError) do
      EasyCodeSign::Signable::PdfFile.new(fake_pdf.path)
    end
  ensure
    fake_pdf.unlink
  end

  def test_accepts_valid_pdf_file
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    assert_instance_of EasyCodeSign::Signable::PdfFile, signable
  end

  def test_signed_returns_false_for_unsigned_pdf
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    refute signable.signed?
  end

  def test_extract_signature_returns_nil_for_unsigned
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    assert_nil signable.extract_signature
  end

  def test_prepare_for_signing_succeeds
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    signable.prepare_for_signing

    assert_equal "PDF_SIGNING_PLACEHOLDER", signable.content_to_sign
  end

  def test_default_signature_config
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)

    refute signable.signature_config[:visible]
    assert_equal 1, signable.signature_config[:page]
    assert_equal :bottom_right, signable.signature_config[:position]
  end

  def test_visible_signature_option
    signable = EasyCodeSign::Signable::PdfFile.new(
      @temp_pdf.path,
      visible_signature: true,
      signature_position: :top_left
    )

    assert signable.signature_config[:visible]
    assert_equal :top_left, signable.signature_config[:position]
  end

  def test_signature_reason_and_location
    signable = EasyCodeSign::Signable::PdfFile.new(
      @temp_pdf.path,
      signature_reason: "Approved",
      signature_location: "New York"
    )

    assert_equal "Approved", signable.signature_config[:reason]
    assert_equal "New York", signable.signature_config[:location]
  end

  def test_signature_page_option
    signable = EasyCodeSign::Signable::PdfFile.new(
      @temp_pdf.path,
      signature_page: 2
    )

    assert_equal 2, signable.signature_config[:page]
  end

  def test_signable_for_returns_pdf_file
    signable = EasyCodeSign.signable_for(@temp_pdf.path)
    assert_instance_of EasyCodeSign::Signable::PdfFile, signable
  end

  private

  def create_test_pdf(path)
    doc = HexaPDF::Document.new
    page = doc.pages.add
    page.canvas.font("Helvetica", size: 12)
    page.canvas.text("Test PDF Document", at: [100, 700])
    doc.write(path)
  end
end

class PdfVerificationTest < EasyCodeSignTest
  def setup
    @temp_pdf = Tempfile.new(["test", ".pdf"])
    create_test_pdf(@temp_pdf.path)
  end

  def teardown
    @temp_pdf.close
    @temp_pdf.unlink
  end

  def test_verify_unsigned_pdf_returns_error
    verifier = EasyCodeSign::Verifier.new
    result = verifier.verify(@temp_pdf.path)

    refute result.valid?
    assert_any_match(result.errors, /not signed/i)
  end

  def test_verifier_creates_pdf_signable
    verifier = EasyCodeSign::Verifier.new
    result = verifier.verify(@temp_pdf.path)

    assert_equal :pdffile, result.file_type
  end

  private

  def create_test_pdf(path)
    doc = HexaPDF::Document.new
    page = doc.pages.add
    page.canvas.font("Helvetica", size: 12)
    page.canvas.text("Test PDF for verification", at: [100, 700])
    doc.write(path)
  end

  def assert_any_match(array, pattern)
    assert array.any? { |item| item.match?(pattern) },
           "Expected at least one item in #{array.inspect} to match #{pattern.inspect}"
  end
end

class PdfDeferredSigningTest < EasyCodeSignTest
  def setup
    super
    @temp_pdf = Tempfile.new(["deferred_test", ".pdf"])
    create_test_pdf(@temp_pdf.path)
    @key = OpenSSL::PKey::RSA.new(2048)
    @cert = create_test_cert(@key)
    @chain = [@cert]
    @cleanup_files = []
  end

  def teardown
    @temp_pdf.close
    @temp_pdf.unlink
    @cleanup_files.each { |f| File.delete(f) if File.exist?(f) }
    super
  end

  def test_prepare_deferred_returns_request
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    assert_instance_of EasyCodeSign::DeferredSigningRequest, request
    assert_instance_of String, request.digest
    assert_equal :sha256, request.digest_algorithm
    assert File.exist?(request.prepared_pdf_path)
    assert_instance_of Array, request.byte_range
    assert_equal 4, request.byte_range.size
    assert_equal @cert.to_pem, request.certificate.to_pem
    assert_instance_of Time, request.signing_time
    assert_instance_of Time, request.created_at
  end

  def test_prepare_deferred_creates_valid_pdf
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    assert File.exist?(request.prepared_pdf_path)
    header = File.open(request.prepared_pdf_path, "rb") { |f| f.read(5) }
    assert_equal "%PDF-", header
  end

  def test_prepare_deferred_digest_size
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain, digest_algorithm: "sha256")
    track_prepared(request)

    assert_equal 32, request.digest.bytesize
  end

  def test_prepare_deferred_sha512_digest_size
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain, digest_algorithm: "sha512")
    track_prepared(request)

    assert_equal 64, request.digest.bytesize
  end

  def test_deferred_request_serialization_roundtrip
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    hash = request.to_h
    restored = EasyCodeSign::DeferredSigningRequest.from_h(hash)

    assert_equal request.digest, restored.digest
    assert_equal request.digest_algorithm, restored.digest_algorithm
    assert_equal request.prepared_pdf_path, restored.prepared_pdf_path
    assert_equal request.byte_range, restored.byte_range
    assert_equal request.certificate.to_pem, restored.certificate.to_pem
    assert_equal request.certificate_chain.map(&:to_pem), restored.certificate_chain.map(&:to_pem)
    assert_equal request.estimated_size, restored.estimated_size
    assert_equal request.signing_time.to_i, restored.signing_time.to_i
    assert_equal request.created_at.to_i, restored.created_at.to_i
  end

  def test_deferred_request_digest_hex_and_base64
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    assert_equal request.digest.unpack1("H*"), request.digest_hex
    assert_equal Base64.strict_encode64(request.digest), request.digest_base64
  end

  def test_finalize_deferred_produces_signed_pdf
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    # Sign the digest with our test key (simulating external signer)
    raw_signature = @key.sign_raw("sha256", request.digest)

    finalizer = EasyCodeSign::Signable::PdfFile.new(request.prepared_pdf_path)
    signed_path = finalizer.finalize_deferred(request, raw_signature)

    assert File.exist?(signed_path)

    # Verify the signed PDF has a signature
    verifier_signable = EasyCodeSign::Signable::PdfFile.new(signed_path)
    sig = verifier_signable.extract_signature
    refute_nil sig, "Expected signed PDF to have an extractable signature"
    refute_nil sig[:contents]
    refute_nil sig[:byte_range]
  end

  def test_signed_attributes_data_present
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    refute_nil request.signed_attributes_data
    refute_empty request.signed_attributes_data
    refute_nil request.signed_attributes_base64
  end

  def test_signed_attributes_data_hash_matches_digest
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain, digest_algorithm: "sha256")
    track_prepared(request)

    computed_hash = OpenSSL::Digest::SHA256.digest(request.signed_attributes_data)
    assert_equal request.digest, computed_hash,
                 "SHA256(signed_attributes_data) must equal the captured digest"
  end

  def test_webcrypto_style_signing_produces_valid_pdf
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    # Simulate WebCrypto: hash-and-sign in one step (like crypto.subtle.sign)
    raw_signature = @key.sign("SHA256", request.signed_attributes_data)

    finalizer = EasyCodeSign::Signable::PdfFile.new(request.prepared_pdf_path)
    signed_path = finalizer.finalize_deferred(request, raw_signature)

    assert File.exist?(signed_path)

    verifier_signable = EasyCodeSign::Signable::PdfFile.new(signed_path)
    sig = verifier_signable.extract_signature
    refute_nil sig, "Expected signed PDF to have an extractable signature"
    refute_nil sig[:contents]
  end

  def test_signed_attributes_data_serialization_roundtrip
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    hash = request.to_h
    assert hash.key?("signed_attributes_data"), "to_h should include signed_attributes_data"

    restored = EasyCodeSign::DeferredSigningRequest.from_h(hash)
    assert_equal request.signed_attributes_data, restored.signed_attributes_data
  end

  def test_finalize_deferred_raises_on_missing_pdf
    request = EasyCodeSign::DeferredSigningRequest.new(
      digest: "\x00" * 32,
      digest_algorithm: :sha256,
      prepared_pdf_path: "/nonexistent/path/missing.pdf",
      byte_range: [0, 100, 200, 100],
      certificate: @cert,
      certificate_chain: @chain,
      estimated_size: 8192,
      signing_time: Time.now
    )

    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)

    assert_raises(EasyCodeSign::DeferredSigningError) do
      signable.finalize_deferred(request, "fake_sig")
    end
  end

  def test_finalize_deferred_raises_on_oversized_signature
    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path)
    request = signable.prepare_deferred(@cert, @chain)
    track_prepared(request)

    # Create a signature that's way too large for the reserved space
    oversized_signature = "\xFF" * (request.estimated_size * 3)

    finalizer = EasyCodeSign::Signable::PdfFile.new(request.prepared_pdf_path)

    assert_raises(EasyCodeSign::DeferredSigningError) do
      finalizer.finalize_deferred(request, oversized_signature)
    end
  end

  private

  def track_prepared(request)
    @cleanup_files << request.prepared_pdf_path
  end

  def create_test_pdf(path)
    doc = HexaPDF::Document.new
    page = doc.pages.add
    page.canvas.font("Helvetica", size: 12)
    page.canvas.text("Deferred signing test document", at: [100, 700])
    doc.write(path)
  end

  def create_test_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test Deferred Signer")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 86_400
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end

class ExternalSigningCallbackTest < Minitest::Test
  def test_callback_receives_data_and_returns_signature
    expected_signature = "mock_signature"
    callback = EasyCodeSign::Signable::ExternalSigningCallback.new(->(data) { expected_signature })

    result = callback.sign("test data", "SHA256")
    assert_equal expected_signature, result
  end

  def test_callback_is_private
    callback = EasyCodeSign::Signable::ExternalSigningCallback.new(->(_) { "sig" })
    assert callback.private?
  end
end

class ExternalSigningProxyTest < Minitest::Test
  def setup
    @key = OpenSSL::PKey::RSA.new(2048)
    @cert = create_test_cert(@key)
  end

  def test_proxy_returns_precomputed_signature
    signature = "precomputed_signature"
    proxy = EasyCodeSign::Signable::ExternalSigningProxy.new(signature, @cert, [@cert])

    result = proxy.sign("any data", "SHA256")
    assert_equal signature, result
  end

  def test_proxy_has_certificate
    proxy = EasyCodeSign::Signable::ExternalSigningProxy.new("sig", @cert, [@cert])
    assert_equal @cert, proxy.certificate
  end

  def test_proxy_is_private
    proxy = EasyCodeSign::Signable::ExternalSigningProxy.new("sig", @cert, [@cert])
    assert proxy.private?
  end

  private

  def create_test_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 86_400
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end
