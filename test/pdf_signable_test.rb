# frozen_string_literal: true

require "test_helper"
require "tempfile"
require "openssl"

class PdfFileSignableTest < EasyCodeSignTest
  def setup
    @temp_pdf = Tempfile.new(["test", ".pdf"])
    create_minimal_pdf(@temp_pdf.path)
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

  def test_apply_signature_produces_signed_pdf
    key  = generate_rsa_key
    cert = build_self_signed_cert(key)
    out  = Tempfile.new(["signed", ".pdf"])

    signable = EasyCodeSign::Signable::PdfFile.new(
      @temp_pdf.path,
      output_path: out.path,
      signature_reason: "Testing"
    )

    signed_path = signable.apply_signature(
      ->(hash) { key.sign_raw("SHA256", hash) },
      [cert]
    )

    assert File.exist?(signed_path)

    verifier = EasyCodeSign::Signable::PdfFile.new(signed_path)
    sig = verifier.extract_signature

    assert sig, "Expected a signature to be present"
    assert sig[:contents], "Expected /Contents to be non-empty"
    assert_equal 4, sig[:byte_range].size
  ensure
    out.close
    out.unlink
  end

  def test_signed_returns_true_after_signing
    key  = generate_rsa_key
    cert = build_self_signed_cert(key)
    out  = Tempfile.new(["signed2", ".pdf"])

    signable = EasyCodeSign::Signable::PdfFile.new(@temp_pdf.path, output_path: out.path)
    signable.apply_signature(->(hash) { key.sign_raw("SHA256", hash) }, [cert])

    verifier = EasyCodeSign::Signable::PdfFile.new(out.path)
    assert verifier.signed?
  ensure
    out.close
    out.unlink
  end

  private

  def generate_rsa_key
    OpenSSL::PKey::RSA.generate(2048)
  end

  def build_self_signed_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = 1
    cert.subject    = OpenSSL::X509::Name.parse("/CN=Test Signer")
    cert.issuer     = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after  = Time.now + 86_400
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  # Builds a minimal valid PDF using only stdlib — no hexapdf or prawn.
  def create_minimal_pdf(path)
    hdr  = "%PDF-1.4\n"
    obj1 = "1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n"
    obj2 = "2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n"
    obj3 = "3 0 obj\n<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>\nendobj\n"

    o1 = hdr.bytesize
    o2 = o1 + obj1.bytesize
    o3 = o2 + obj2.bytesize
    xref_off = o3 + obj3.bytesize

    xref = "xref\n0 4\n" \
           "0000000000 65535 f \n" \
           "#{o1.to_s.rjust(10, "0")} 00000 n \n" \
           "#{o2.to_s.rjust(10, "0")} 00000 n \n" \
           "#{o3.to_s.rjust(10, "0")} 00000 n \n"

    trailer = "trailer\n<</Size 4 /Root 1 0 R>>\nstartxref\n#{xref_off}\n%%EOF\n"

    File.binwrite(path, hdr + obj1 + obj2 + obj3 + xref + trailer)
  end
end

class PdfVerificationTest < EasyCodeSignTest
  def setup
    @temp_pdf = Tempfile.new(["test", ".pdf"])
    create_minimal_pdf(@temp_pdf.path)
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

  def assert_any_match(array, pattern)
    assert array.any? { |item| item.match?(pattern) },
           "Expected at least one item in #{array.inspect} to match #{pattern.inspect}"
  end

  def create_minimal_pdf(path)
    hdr  = "%PDF-1.4\n"
    obj1 = "1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n"
    obj2 = "2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n"
    obj3 = "3 0 obj\n<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>\nendobj\n"

    o1 = hdr.bytesize
    o2 = o1 + obj1.bytesize
    o3 = o2 + obj2.bytesize
    xref_off = o3 + obj3.bytesize

    xref = "xref\n0 4\n" \
           "0000000000 65535 f \n" \
           "#{o1.to_s.rjust(10, "0")} 00000 n \n" \
           "#{o2.to_s.rjust(10, "0")} 00000 n \n" \
           "#{o3.to_s.rjust(10, "0")} 00000 n \n"

    trailer = "trailer\n<</Size 4 /Root 1 0 R>>\nstartxref\n#{xref_off}\n%%EOF\n"

    File.binwrite(path, hdr + obj1 + obj2 + obj3 + xref + trailer)
  end
end
