require 'Set'
class VulnAggregator
  include Enumerable
  SEVERITY_TYPES = ['catastrophic', 'critical', 'high', 'medium', 'low', 'unknown']

  class SeverityTypeError < StandardError
  end

  def initialize()
    @all = []
    @by_severity = {}
    @by_image = {}
    @by_target = {}
    @images = ::Set.new
    @targets = ::Set.new
    SEVERITY_TYPES.each { |type| @by_severity[type] = [] }
  end

  def add(vuln)
    raise SeverityTypeError.new("Unknown Severity Type #{vuln.severity}") unless @by_severity.has_key?(vuln.severity)
    @all.push(vuln)
    @by_severity[vuln.severity].push(vuln)
    @by_image[vuln.image] ||= []
    @by_image[vuln.image].push(vuln)
    @by_target[vuln.target] ||= []
    @by_target[vuln.target].push(vuln)
    @images.add(vuln.image)
    @targets.add(vuln.target)
  end

  def total_vuln_count
    SEVERITY_TYPES.inject(0) {|sum, type| sum += self.send("#{type}_count") }
  end

  SEVERITY_TYPES.each do |type|
    define_method "#{type}_count" do
      @by_severity[type].count
    end
  end

  def by_severity(severity)
    subset = self.class.new()
    @by_severity[severity].map { |v| subset.add(v) }
    subset
  end

  def by_image(image)
    subset = self.class.new()
    @by_image[image].map { |v| subset.add(v) }
    subset
  end

  def by_target(target)
    subset = self.class.new()
    @by_target[target].map { |v| subset.add(v) }
    subset
  end

  def images
    @images
  end

  def targets
    @targets
  end

  def severities
    SEVERITY_TYPES
  end

  def each(&block)
    @all.each(&block)
  end

end

