require 'rspec'
require_relative '../../models/vuln_aggregator'

RSpec.describe VulnAggregator, "#severity" do

  def vuln(severity = "low", image = "kube-proxy:1.2", target = "someregistry.example.org/kube-proxy:1.2")
    double(:vuln, severity: severity, image: image, target: target)
  end

  context "when a vulnerability with unknown severity type is added" do
    it "should throw an error" do
      aggregator = VulnAggregator.new
      vuln_with_bad_type = vuln("unknown-severity")
      expect { aggregator.add(vuln_with_bad_type) }.to raise_error(VulnAggregator::SeverityTypeError)
    end
  end

  it "should be able to return total counts of added vulnerabilities by type" do
      aggregator = VulnAggregator.new
      expect(aggregator.catastrophic_count).to eq(0)
      expect(aggregator.critical_count).to eq(0)
      expect(aggregator.high_count).to eq(0)
      expect(aggregator.medium_count).to eq(0)
      expect(aggregator.low_count).to eq(0)
      expect(aggregator.unknown_count).to eq(0)

      aggregator.add(vuln("catastrophic"))
      aggregator.add(vuln("critical"))
      aggregator.add(vuln("high"))
      aggregator.add(vuln("medium"))
      aggregator.add(vuln("low"))
      aggregator.add(vuln("unknown"))

      expect(aggregator.catastrophic_count).to eq(1)
      expect(aggregator.critical_count).to eq(1)
      expect(aggregator.high_count).to eq(1)
      expect(aggregator.medium_count).to eq(1)
      expect(aggregator.low_count).to eq(1)
      expect(aggregator.unknown_count).to eq(1)
  end

  it "can return 'subsets' (vuln aggregators) by severity" do
    vuln1 = vuln("critical", "foo:1.2")
    vuln2 = vuln("critical", "bar:3.4")
    vuln3 = vuln("high", "baz:5.6")

    aggregator = VulnAggregator.new
    aggregator.add(vuln1)
    aggregator.add(vuln2)
    aggregator.add(vuln3)

    results = aggregator.by_severity("critical")
    expect(results).to include(vuln1)
    expect(results).to include(vuln2)
    expect(results).not_to include(vuln3)
    expect(results.critical_count).to eq(2)
    expect(results.high_count).to eq(0)
  end

  it "returns a subset by severity even if no vulns with that severity exist" do
    vuln1 = vuln("critical", "foo:1.2")
    vuln2 = vuln("critical", "bar:3.4")
    vuln3 = vuln("high", "baz:5.6")

    aggregator = VulnAggregator.new
    aggregator.add(vuln1)
    aggregator.add(vuln2)
    aggregator.add(vuln3)

    results = aggregator.by_severity("low")
    expect(results.total_vuln_count).to eq(0)
  end

  it "can return 'subsets' (vuln aggregators) by image" do
    vuln1 = vuln("critical", "foo:1.2")
    vuln2 = vuln("critical", "foo:1.2")
    vuln3 = vuln("high", "foo:1.2")
    vuln4 = vuln("low", "bar:3.4")

    aggregator = VulnAggregator.new
    aggregator.add(vuln1)
    aggregator.add(vuln2)
    aggregator.add(vuln3)
    aggregator.add(vuln4)

    results = aggregator.by_image("foo:1.2")
    expect(results).to include(vuln1)
    expect(results).to include(vuln2)
    expect(results).to include(vuln3)
    expect(results).not_to include(vuln4)
    expect(results.critical_count).to eq(2)
    expect(results.high_count).to eq(1)
    expect(results.low_count).to eq(0)
  end

  it "returns a list of images" do
    vuln1 = vuln("critical", "foo:1.2")
    vuln2 = vuln("critical", "bar:3.4")
    vuln3 = vuln("high", "baz:5.6")
    aggregator = VulnAggregator.new

    aggregator.add(vuln1)
    aggregator.add(vuln2)
    aggregator.add(vuln3)

    results = aggregator.images
    expect(results).to include("foo:1.2")
    expect(results).to include("bar:3.4")
    expect(results).to include("baz:5.6")
  end

  it "can return 'subsets' (vuln aggregators) by target" do
    vuln1 = vuln("critical", "foo:1.2", "target1")
    vuln2 = vuln("critical", "foo:1.2", "target1")
    vuln3 = vuln("high", "foo:1.2", "target1")
    vuln4 = vuln("low", "bar:3.4", "target2")

    aggregator = VulnAggregator.new
    aggregator.add(vuln1)
    aggregator.add(vuln2)
    aggregator.add(vuln3)
    aggregator.add(vuln4)

    results = aggregator.by_target("target1")
    expect(results).to include(vuln1)
    expect(results).to include(vuln2)
    expect(results).to include(vuln3)
    expect(results).not_to include(vuln4)
    expect(results.critical_count).to eq(2)
    expect(results.high_count).to eq(1)
    expect(results.low_count).to eq(0)
  end

  it "returns a list of targets" do
    vuln1 = vuln("critical", "foo:1.2", "target1")
    vuln2 = vuln("critical", "foo:1.2", "target2")
    vuln3 = vuln("low", "bar:3.4", "target3")
    aggregator = VulnAggregator.new

    aggregator.add(vuln1)
    aggregator.add(vuln2)
    aggregator.add(vuln3)

    results = aggregator.targets
    expect(results).to include("target1")
    expect(results).to include("target2")
    expect(results).to include("target3")
  end

  it "returns severity types" do
    aggregator = VulnAggregator.new
    expect(aggregator.severities).to eq(['catastrophic', 'critical', 'high', 'medium', 'low', 'unknown'])
  end

end
