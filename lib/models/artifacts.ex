defmodule Hawk.Models.Artifacts do
  defstruct ts: 0,
            nonce: nil,
            method: :post,
            resource: nil,
            host: nil,
            port: 443,
            hash: nil,
            ext: nil,
            app: nil,
            dlg: nil
end
