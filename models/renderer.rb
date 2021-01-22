class Renderer
  def initialize(vuln_aggregator)
    @vuln_aggregator = vuln_aggregator
  end

  def text_report(severities)
    summary = []
    severities.each do |severity|
      severity_results = @vuln_aggregator.by_severity(severity)
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
    string = "OVERALL: Catastrophic: #{@vuln_aggregator.catastrophic_count}, "
    string += "Critical: #{@vuln_aggregator.critical_count}, "
    string += "High: #{@vuln_aggregator.high_count}, "
    string += "Medium: #{@vuln_aggregator.medium_count}, "
    string += "Low: #{@vuln_aggregator.low_count}, "
    string += "Unknown: #{@vuln_aggregator.unknown_count}"
    summary.push(string)
    summary.join("\n")
  end
end
