require 'optparse'
class FlagParser

  Config = Struct.new(:format, :severity_filter)
  def self.parse!(argv)
    #you must mutate a hash with opt_parse and also
    #destructively mutate ARGV if you want non-flag args -- kinda gross.
    config = Config.new
    config.format = 'text'
    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: render.rb [options] [directory]"
      opts.on("-fFORMAT", "--format=FORMAT", "Choose an output format, valid values: 'text' (default), 'csv'") do |format|
        config.format = format
      end
      opts.on("-sSEVERITY", "--severity=SEVERITY", "Filter for a specific severity: #{VulnAggregator::SEVERITY_TYPES.join(", ")}") do |severity|
        config.severity_filter = severity
      end
      opts.on("-h", "--help", "Prints this help") do
        puts opts
        exit
      end
    end

    if (argv.length == 0)
      opt_parser.parse %w[--help]
    end
    opt_parser.parse!(argv) #config now has command line options.
    config
  end

end
