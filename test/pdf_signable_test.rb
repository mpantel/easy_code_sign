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
