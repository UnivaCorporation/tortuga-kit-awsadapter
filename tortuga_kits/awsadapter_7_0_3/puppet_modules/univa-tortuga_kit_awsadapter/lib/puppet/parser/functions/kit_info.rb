module Puppet::Parser::Functions
  newfunction(:kit_info, :type => :rvalue) do |args|
    JSON.parse(
      File.read(
        Pathname.new(__FILE__).dirname
          .join('../../../../kit.json')))
  end
end
