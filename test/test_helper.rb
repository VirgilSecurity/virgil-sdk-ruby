require 'virgil/sdk'

require 'minitest/autorun'
require 'minitest/reporters'
require 'envyable'

Envyable.load('./test/support/env.yml')

Minitest::Reporters.use! Minitest::Reporters::DefaultReporter.new

root_path = File.expand_path('../', __FILE__)
Dir[File.join(root_path, 'support/**/*.rb')].each { |f| require f }
