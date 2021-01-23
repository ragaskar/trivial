require_relative './models/vulnerability.rb'
require_relative './models/vuln_aggregator.rb'
require_relative './models/trivy_json_parser.rb'
require_relative './models/flag_parser.rb'
require_relative './models/renderer.rb'
require 'JSON'


config = FlagParser.parse!(ARGV) #destructively mutates ARGV such that all flags params are removed.
vuln_aggregator = TrivyJsonParser.new.parse(ARGV[0])
#RENDER
renderer = Renderer.new(vuln_aggregator)

case config.format
when 'text'
  puts renderer.text_report(config.severity_filter ? [config.severity_filter] : vuln_aggregator.severities)
when 'csv'
  puts renderer.csv_report(config.severity_filter ? [config.severity_filter] : vuln_aggregator.severities)
end

