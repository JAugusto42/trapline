# frozen_string_literal: true

module Trapline
  module Languages
    Lang = Struct.new(:key, :name, :extension, :comment, :aliases, keyword_init: true)

    ALL = [
      Lang.new(key: "ruby",       name: "Ruby",       extension: "rb",    comment: "#",  aliases: %w[rb]),
      Lang.new(key: "python",     name: "Python",     extension: "py",    comment: "#",  aliases: %w[py python3]),
      Lang.new(key: "javascript", name: "JavaScript", extension: "js",    comment: "//", aliases: %w[js]),
      Lang.new(key: "typescript", name: "TypeScript", extension: "ts",    comment: "//", aliases: %w[ts]),
      Lang.new(key: "java",       name: "Java",       extension: "java",  comment: "//", aliases: []),
      Lang.new(key: "go",         name: "Go",         extension: "go",    comment: "//", aliases: %w[golang]),
      Lang.new(key: "php",        name: "PHP",        extension: "php",   comment: "//", aliases: []),
      Lang.new(key: "csharp",     name: "C#",         extension: "cs",    comment: "//", aliases: %w[cs c#]),
      Lang.new(key: "kotlin",     name: "Kotlin",     extension: "kt",    comment: "//", aliases: %w[kt]),
      Lang.new(key: "scala",      name: "Scala",      extension: "scala", comment: "//", aliases: []),
      Lang.new(key: "rust",       name: "Rust",       extension: "rs",    comment: "//", aliases: []),
      Lang.new(key: "c",          name: "C",          extension: "c",     comment: "//", aliases: []),
      Lang.new(key: "cpp",        name: "C++",        extension: "cpp",   comment: "//", aliases: %w[c++]),
      Lang.new(key: "swift",      name: "Swift",      extension: "swift", comment: "//", aliases: []),
      Lang.new(key: "bash",       name: "Bash",       extension: "sh",    comment: "#",  aliases: %w[sh]),
      Lang.new(key: "yaml",       name: "YAML",       extension: "yaml",  comment: "#",  aliases: %w[yml]),
      Lang.new(key: "json",       name: "JSON",       extension: "json",  comment: "//", aliases: []),
      Lang.new(key: "dockerfile", name: "Dockerfile", extension: "dockerfile", comment: "#", aliases: %w[docker]),
      Lang.new(key: "terraform",  name: "Terraform",  extension: "tf",    comment: "#",  aliases: %w[hcl tf]),
      Lang.new(key: "generic",    name: "Generic",    extension: "txt",   comment: "#",  aliases: []),
      Lang.new(key: "regex",      name: "Regex",      extension: "txt",   comment: "#",  aliases: %w[none])
    ].freeze

    module_function

    def all
      ALL
    end

    def keys
      ALL.flat_map { |l| [l.key, *l.aliases] }
    end

    def find(name)
      return nil if name.nil?

      n = name.to_s.downcase
      ALL.find { |l| l.key == n || l.aliases.include?(n) }
    end

    def known?(name)
      !find(name).nil?
    end

    def extension_for(name)
      find(name)&.extension || "txt"
    end

    def comment_for(name)
      find(name)&.comment || "#"
    end

    def from_extension(ext)
      e = ext.to_s.delete_prefix(".").downcase
      ALL.find { |l| l.extension == e }
    end
  end
end
