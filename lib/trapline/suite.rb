# frozen_string_literal: true

module Trapline
  class Suite
    Result = Struct.new(:slug, :status, :passed, :total, :errors, :failures, keyword_init: true)

    def initialize(store: Trapline.store, engine: Trapline.engine)
      @store = store
      @engine = engine
    end

    def run
      raise Error, "no engine found: install opengrep or semgrep" unless @engine

      @store.list.map { |entry| run_one(entry) }
    end

    private

    def run_one(entry)
      slug = entry[:slug]
      return result(slug, "error", errors: [entry[:error]]) if entry[:error]

      rule = @store.read(slug)
      validation = Validator.new.validate(rule[:yaml])
      return result(slug, "error", errors: validation.errors.map { |i| "#{i.path}: #{i.message}" }) unless validation.valid?
      return result(slug, "skipped") unless rule[:test_code]

      res = @engine.run(rule[:yaml], code: rule[:test_code], language: rule[:test_language])
      ann = res.annotations || { passed: 0, total: 0, results: [] }
      failures = ann[:results].select { |r| r[:status] == "fail" }.map { |r| r[:reason] }
      status = if res.errors.any? then "error"
               elsif ann[:total].zero? then "no-annotations"
               elsif failures.any? then "fail"
               else "pass"
               end
      result(slug, status, passed: ann[:passed], total: ann[:total], errors: res.errors, failures: failures)
    end

    def result(slug, status, passed: 0, total: 0, errors: [], failures: [])
      Result.new(slug: slug, status: status, passed: passed, total: total, errors: errors, failures: failures)
    end
  end
end
