
require_relative '../../../test_helper'

class OmniAuth::OpenIDConnect::UtilTest < MiniTest::Test
  def test_hash_deep_check
    h1 = {}; h2 = {}
    OmniAuth::OpenIDConnect.hash_deep_check(h1, h2)
  end
end
