#!/usr/bin/env


module PCI

  CARD_PROVIDER_CODES = {
    'VISA'       => ["4"],
    'MASTER'     => ["5", "601900","603634", "636094", "67", "63", "6027"],
    'AMEX'       => ["34", "37"],
    'DISCOVER'   => ["6011", "622", "64", "65", "36", "30", "38"],
    'JCB'        => ["35"],
    'CUP'        => ["62"],
    'DAVIDJONES' => ["214001"]
  }

  module_function

  def get_credit_card_provider(card_number)
    PCI::CARD_PROVIDER_CODES.each_key do |k|
      PCI::CARD_PROVIDER_CODES[k].each do |code|
        return k if card_number.start_with? code
      end
    end
    nil
  end

  def get_credit_card_data(str)
    data = nil
    res = str.match(/B([3-6][0-9]{14,15})\^.+\^([0-9]{4})([0-9]{3})/) do |m|
      data = {
        :number   => m[1],
        :expiry   => m[2].scan(/../).reverse.join('/'),
        :provider => get_credit_card_provider(m[1]),
        :service  => m[3],
      }
    end
    data
  end

  def credit_card_valid? (account_number)
    digits = account_number.scan(/./).map(&:to_i)
    check = digits.pop
    check = 10 if check == 0

    sum = digits.reverse.each_slice(2).map do |x, y|
      y = 0 if !y
      [(x * 2).divmod(10), y]
    end.flatten.inject(:+)

    (10 - sum % 10) == check
  end

end #PCI
