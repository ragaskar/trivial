require_relative './models/vulnerability.rb'
require_relative './models/vuln_aggregator.rb'
require_relative './models/trivy_json_parser.rb'
require_relative './models/flag_parser.rb'
require 'JSON'


config = FlagParser.parse!(ARGV) #destructively mutates ARGV such that all flags params are removed.
vuln_aggregator = TrivyJsonParser.new.parse(ARGV[0])
#RENDER
if config.format == 'text'
  summary = []
  severities = config.severity_filter ? [config.severity_filter] : vuln_aggregator.severities
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
          summary.push("\tTarget: #{target}\n")
          target_results.each do |target_vuln|
            summary.push("\t  #{target_vuln.vulnerability_id} #{target_vuln.package_name} #{target_vuln.title} (Score #{target_vuln.score})")
            summary.push("\t  #{target_vuln.url}")
            summary.push("\t  #{target_vuln.description}")
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
end
