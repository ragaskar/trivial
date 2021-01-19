require_relative './models/vulnerability.rb'
require_relative './models/vuln_aggregator.rb'
require 'JSON'
#PARSE
scan_results_directory = ARGV[0]
vuln_aggregator = VulnAggregator.new()
relative_filenames = Dir[File.join(scan_results_directory, "*")]
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

  # func imageVersionPath(imagePath string, imageTag string) string {
  # return fmt.Sprintf("%s:%s", imagePath, imageTag)
  # }
  #fileSafeImagePath := strings.ReplaceAll(imageVersionPath(image.path, image.tag), "/", "__")
  #
  #

  filename = File.basename(relative_filename)
  #may not work if there is a : in the imagePath or Tag. ;)
  imagePath, imageTag = filename.sub(".trivy.json", "").sub("__", "/").split(":")

  if (!results.empty?)
    results.each do |result|
      target_vuln_data = result["Vulnerabilities"] || []
      target_vuln_data.each do |vuln_data|
        vuln = Vulnerability.new(imagePath, imageTag, result["Target"], vuln_data)
        vuln_aggregator.add(vuln)
      end
    end
  end
end
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
