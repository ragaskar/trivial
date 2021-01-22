class Renderer
  def initialize(vuln_aggregator)
    @vuln_aggregator = vuln_aggregator
  end

  def text_report(severities)
    summary = []
    severities.each do |severity|
      severity_results =  grouped_result_set(severity)
      if severity_results.length == 0
        summary.push("No #{severity} vulnerabilities found")
        next
      else
        summary.push("\n\n>>> #{severity} vulnerabilities\n\n".upcase)
        image = nil
        target = nil

        severity_results.each do |result|
          if image != result.image
            image = result.image
            summary.push("IMAGE: #{image}\n")
            target = nil
          end
          if target != result.target
            target = result.target
            summary.push("\tTarget: #{target}\n")
          end
          summary.push("\t  #{result.vulnerability_id} #{result.package_name} #{result.title} (Score #{result.score})")
          summary.push("\t  #{result.url}")
          summary.push("\t  #{result.description}")
          summary.push("\n")
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

  private
  def grouped_result_set(severity)
    by_severity_vulns = @vuln_aggregator.by_severity(severity)
    #sort by image + target
    by_severity_vulns.sort_by { |v| [v.image, v.target] }
  end
end
