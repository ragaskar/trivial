require 'rspec'
require_relative '../../models/vuln_aggregator'

RSpec.describe VulnAggregator, "#severity" do

  def vuln(severity = "low")
    double(:vuln, severity: severity)
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
end
