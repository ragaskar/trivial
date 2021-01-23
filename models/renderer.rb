require 'csv'

class Renderer
  def initialize(vuln_aggregator)
    @vuln_aggregator = vuln_aggregator
  end

  def csv_report(severities)
    results = @vuln_aggregator.select { |v| severities.include?(v.severity) }.sort_by { |v| [VulnAggregator::SEVERITY_TYPES.index(v.severity), v.image, v.target] }
    CSV.generate do |csv|
      cols = [
        ["vulnerability_id", "CVE ID"],
        ["severity", "Severity"],
        ["score", "Score"],
        ["image", "Image"],
        ["target", "Target"],
        ["package_name", "Package Name"],
        ["title", "Title"],
        ["url", "URL"],
        ["description", "Description"]
      ]
      csv << cols.map { |c| c[1] }
      results.each do |v|
        csv << cols.map { |c| v.send(c[0]) }
      end
    end
  end

  def text_report(severities)
    summary = []
    severities.each do |severity|
      by_severity_vulns = @vuln_aggregator.by_severity(severity)
      severity_results =  by_severity_vulns.sort_by { |v| [v.image, v.target] }
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

end
