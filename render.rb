class Vulnerability
  def initialize(data)
    @data = data
  end

  def severity
    severity = @data["Severity"].downcase
    return severity if severity != "critical"

    max_cvss_score = @data["CVSS"].inject(0) do |max_score, (source, score_data)|
      score = score_data["V3Score"] || 0
      max_score = [max_score, score].max
    end
    if max_cvss_score == 10
      "catastrophic"
    else
      "critical"
    end
  end
end

class TargetResults
  SEVERITY_TYPES = ['catastrophic', 'critical', 'high', 'medium', 'low', 'unknown']

  class SeverityTypeError < StandardError
  end

  def initialize()
    @results = {}
    SEVERITY_TYPES.each { |type| @results[type] = [] }
  end

  def add(vuln)
    raise SeverityTypeError.new("Unknown Severity Type #{vuln.severity}") unless @results.has_key?(vuln.severity)
    @results[vuln.severity].push(vuln)
  end

  def total_vuln_count
    SEVERITY_TYPES.inject(0) {|sum, type| sum += self.send("#{type}_count") }
  end

  SEVERITY_TYPES.each do |type|
    #not right for catastrophic/critical :)
    define_method "#{type}_count" do
      @results[type].count
    end
  end

end

require 'JSON'
#PARSE
scan_results_directory = ARGV[0]
relative_filenames = Dir[File.join(scan_results_directory, "*")]
scan_results_by_target = {}
relative_filenames.each do |relative_filename|
  #whole file goes in memory, may not scale but easy
  result_json = File.read(relative_filename)
  if result_json == "null" || result_json == ""
    puts "Skipping #{relative_filename}, content was '#{result_json}'"
    next
  end
  begin
  results = JSON.parse(result_json)
  rescue JSON::ParserError => e
    puts "Error #{e} while parsing #{relative_filename}"
  end

  if (!results.empty?)
    results.each do |result|
      target = result["Target"]
      target_results = scan_results_by_target[target] ||= TargetResults.new()
      target_vuln_data = result["Vulnerabilities"] || []
      target_vuln_data.each do |vuln_data|
        vuln = Vulnerability.new(vuln_data)
        target_results.add(vuln)
      end
    end
  end
end
#RENDER
puts "\n\n"
summary = []
overall_catastrophic = 0
overall_critical = 0
overall_high = 0
overall_medium = 0
overall_low = 0
overall_unknown = 0
scan_results_by_target.each do |target, target_results|
  if target_results.total_vuln_count == 0
    summary.push("#{target}: No vulnerabilities found")
  else
    string = "#{target}: Catastrophic: #{target_results.catastrophic_count}, "
    string += "Critical: #{target_results.critical_count}, "
    string += "High: #{target_results.high_count}, "
    string += "Medium: #{target_results.medium_count}, "
    string += "Low: #{target_results.low_count}, "
    string += "Unknown: #{target_results.unknown_count}"
    summary.push(string)
    overall_catastrophic += target_results.catastrophic_count
    overall_critical += target_results.critical_count
    overall_high += target_results.high_count
    overall_medium += target_results.medium_count
    overall_low += target_results.low_count
    overall_unknown += target_results.unknown_count
  end
end
puts summary.join("\n")
puts "\n\n"
string = "OVERALL: Catastrophic: #{overall_catastrophic}, "
string += "Critical: #{overall_critical}, "
string += "High: #{overall_high}, "
string += "Medium: #{overall_medium}, "
string += "Low: #{overall_low}, "
string += "Unknown: #{overall_unknown}"
puts string
