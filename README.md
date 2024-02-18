# Linzer

Linzer is a Ruby library for [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421.html).

## Install

Add the following line to your `Gemfile`:

```ruby
gem "linzer"
```

Or just `gem install linzer`.

## Usage

TODO: Write usage instructions here

For now just take a look at the unit tests.

It's still early days, so only signatures RSASSA-PSS Using SHA-512 like ones described in the RFC are supported. I'll be expanding the library to cover more functionality specified in the RFC in subsequent releases.


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nomadium/linzer. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Linzer project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).
