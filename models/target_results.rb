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

