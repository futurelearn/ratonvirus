# frozen_string_literal: true

class AntivirusValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    # Avoid unnecessary scans in case
    # a) the storage backend does not accept the resource
    # b) the attribute has not changed
    storage = Ratonvirus.storage
    return unless storage.accept?(value)
    return unless storage.changed?(record, attribute)

    # Only scan if the scanner is available
    scanner = Ratonvirus.scanner

    if scanner.available?
      return unless scanner.virus?(value)

      if scanner.errors.any?
        scanner.errors.each do |err|
          record.errors.add attribute, err
        end
      else
        record.errors.add attribute, :antivirus_virus_detected
      end
    else
      record.errors.add attribute, :antivirus_not_installed
    end
  end
end
