require "helper"
require "fluent/plugin/filter_sanitizer.rb"

class SanitizerFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  test "failure" do
    flunk
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::SanitizerFilter).configure(conf)
  end
end
