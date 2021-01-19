require_relative './models/vulnerability.rb'
require_relative './models/vuln_aggregator.rb'
require_relative './models/trivy_json_parser.rb'
require 'JSON'
#PARSE
scan_results_directory = ARGV[0]
vuln_aggregator = TrivyJsonParser.new.parse(scan_results_directory)
#RENDER
puts "\n\n"
summary = []
severities = vuln_aggregator.severities
severities.each do |severity|
  severity_results = vuln_aggregator.by_severity(severity)
  if severity_results.total_vuln_count == 0
    summary.push("No #{severity} vulnerabilities found")
    next
  else
    summary.push("\n\n>>> #{severity} vulnerabilities\n\n".upcase)
    images = severity_results.images
    images.each do |image|
      summary.push("IMAGE: #{image}\n")
      image_results = severity_results.by_image(image)
      targets = image_results.targets
      targets.each do |target|
        target_results = image_results.by_target(target)
        target_results.each do |target_vuln|
          summary.push("Target: #{target_vuln.target}")
          summary.push("#{target_vuln.vulnerability_id} : Score #{target_vuln.score}")
          summary.push("#{target_vuln.url}")
          summary.push("#{target_vuln.description}")
          summary.push("\n")
        end
      end
    end
  end
end

puts summary.join("\n")
puts "\n\n"
string = "OVERALL: Catastrophic: #{vuln_aggregator.catastrophic_count}, "
string += "Critical: #{vuln_aggregator.critical_count}, "
string += "High: #{vuln_aggregator.high_count}, "
string += "Medium: #{vuln_aggregator.medium_count}, "
string += "Low: #{vuln_aggregator.low_count}, "
string += "Unknown: #{vuln_aggregator.unknown_count}"
puts string
