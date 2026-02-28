# frozen_string_literal: true

module EasyCodeSign
  module Pdf
    # Builds visible signature appearance for PDF signatures
    #
    # Creates an appearance stream that displays signature information
    # in the PDF document (signer name, date, reason, etc.)
    #
    class AppearanceBuilder
      POSITIONS = {
        top_left: ->(box) { [36, box.height - 36 - 50, 236, box.height - 36] },
        top_right: ->(box) { [box.width - 236, box.height - 36 - 50, box.width - 36, box.height - 36] },
        bottom_left: ->(box) { [36, 36, 236, 86] },
        bottom_right: ->(box) { [box.width - 236, 36, box.width - 36, 86] }
      }.freeze

      def initialize(document, config, certificate)
        @document = document
        @config = config
        @certificate = certificate
      end

      # Build appearance stream for visible signature
      # @param widget [HexaPDF::Type::Annotations::Widget] the signature widget
      # @return [void]
      def build_appearance(widget)
        rect = widget[:Rect].value
        width = rect[2] - rect[0]
        height = rect[3] - rect[1]

        # Create appearance form XObject
        form = @document.add({ Type: :XObject, Subtype: :Form, BBox: [0, 0, width, height] })
        canvas = form.canvas

        # Draw border
        canvas.stroke_color(0, 0, 0)
        canvas.line_width(1)
        canvas.rectangle(0.5, 0.5, width - 1, height - 1)
        canvas.stroke

        # Draw text content
        draw_signature_text(canvas, width, height)

        # Set as widget's normal appearance
        widget[:AP] = { N: form }
      end

      # Calculate signature rectangle for a given position
      # @param page [HexaPDF::Type::Page] the page
      # @param position [Symbol] position preset
      # @return [Array<Numeric>] rectangle coordinates [x1, y1, x2, y2]
      def self.calculate_rect(page, position, custom_rect: nil)
        return custom_rect if custom_rect

        box = page.box(:media)
        calculator = POSITIONS[position.to_sym] || POSITIONS[:bottom_right]
        calculator.call(box)
      end

      private

      def draw_signature_text(canvas, width, height)
        canvas.font("Helvetica", size: 8)
        canvas.fill_color(0, 0, 0)

        y_offset = height - 12
        x_offset = 5

        # Signer name
        signer = extract_signer_name
        canvas.text("Digitally signed by:", at: [x_offset, y_offset])
        y_offset -= 10
        canvas.text(signer, at: [x_offset, y_offset])
        y_offset -= 12

        # Reason (if provided)
        if @config[:reason]
          canvas.text("Reason: #{@config[:reason]}", at: [x_offset, y_offset])
          y_offset -= 10
        end

        # Location (if provided)
        if @config[:location]
          canvas.text("Location: #{@config[:location]}", at: [x_offset, y_offset])
          y_offset -= 10
        end

        # Date
        canvas.text("Date: #{Time.now.strftime('%Y-%m-%d %H:%M:%S %Z')}", at: [x_offset, y_offset])
      end

      def extract_signer_name
        # Try to extract CN from certificate subject
        subject = @certificate.subject.to_a
        cn = subject.find { |name, _, _| name == "CN" }
        return cn[1] if cn

        # Fallback to full subject
        @certificate.subject.to_s
      end
    end
  end
end
