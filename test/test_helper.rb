# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "easy_code_sign"
require "minitest/autorun"

# Base test class with common helpers
class EasyCodeSignTest < Minitest::Test
  def setup
    EasyCodeSign.reset_configuration!
    EasyCodeSign.reset_provider!
  end

  def teardown
    EasyCodeSign.reset_configuration!
    EasyCodeSign.reset_provider!
  end
end
