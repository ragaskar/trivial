class TrivyJsonParser
  def initialize
  end

  def parse(scan_results_directory)
    vuln_aggregator = VulnAggregator.new()
    relative_filenames = Dir[File.join(scan_results_directory, "*")]
    relative_filenames.each do |relative_filename|
      #whole file goes in memory, may not scale but easy
      result_json = File.read(relative_filename)
      if result_json == "null" || result_json == ""
        STDERR.puts "Skipping #{relative_filename}, content was '#{result_json}'"
        next
      end
      begin
        results = JSON.parse(result_json)
      rescue JSON::ParserError => e
        STDERR.puts "Error #{e} while parsing #{relative_filename}"
      end

      # this is specific to our pipeline, not by default in trivy.
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
    vuln_aggregator
  end
end
