#!/usr/bin/env ruby
# rubocop:disable all
require "starry"

def serialize(component)
  case
  when component.match?(/";/), component.start_with?('"')
    Starry.serialize(Starry.parse_item(component))
  when component.match?(/;/)
    field, *params = component.split(/;/)
    item = Starry.parse_item("foo")
    item.value = field
    np = params.map do |p|
      p.split("=").size == 2 ? Hash[*p.split("=")] : { p => true }
    end
    item.parameters = np.shift
    Starry.serialize(item)
  when component.start_with?("@"), component.match?(/^[a-z]/)
    Starry.serialize(Starry.parse_item(Starry.serialize(component)))
  else
    puts "Unsupported: #{component}"
  end
end

%w["@authority";req "@method";req "@path";req "@query-param";name="bar" "@query-param";name="baz" "@query-param";name="fa%C3%A7ade%22%3A%20" "@query-param";name="param" "@query-param";name="qux" "@query-param";name="var" "content-digest";req "date" "example-dict";key="a" "example-dict";key="b" "example-dict";key="c" "example-dict";key="d" "example-dict";sf "example-header";bs @authority @authority;req @invalid-unknown-field-foo @method @method;req @method;wrong @path @path;req @query @query-param;name="bar" @query-param;name="baz" @query-param;name="fa%C3%A7ade%22%3A%20" @query-param;name="non-existent" @query-param;name="not_found" @query-param;name="param" @query-param;name="qux" @query-param;name="var" @query-param;name=%20 @request-target @scheme @signature-params @status @target-uri cache-control content-digest content-digest;req content-length content-type date example-dict example-dict;key="a" example-dict;key="b" example-dict;key="c" example-dict;key="d" example-dict;sf example-dictionary;key="foo" example-header example-header;bs expires;tr field-not-found-foo-bar foo_header forwarded header1 header2 header2;bs header2;bs;req header2;req;bs header3 host missing missing-component signature signature-input trailer user-agent x-baz x-custom-header x-empty-header x-field x-foo x-header x-missing x-not-in-message x-obs-fold-header x-ows-header x-response-custom].each do |c|
  puts serialize(c)
end
