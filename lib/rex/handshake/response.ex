defmodule Rex.Handshake.Response do
  defstruct [:type, :version_number, :network_magic, :query]

  alias Rex.Util

  def validate(response) do
    %{payload: payload} = Util.plex(response)

    case CBOR.decode(payload) do
      # msgAcceptVersion
      {:ok, [1, version, [magic, query]], ""} ->
        if version in [32783, 32784] do
          {:ok,
           %__MODULE__{
             network_magic: magic,
             query: query,
             type: :msg_accept_version,
             version_number: version
           }}
        else
          {:error, "Only versions 32783 and 32784 are supported."}
        end

      # msgRefuse
      {:ok, [2, refuse_reason], ""} ->
        case refuse_reason do
          # TODO: return accepted versions; reduce to 32783 and 32784
          [0, _version_number_binary] ->
            {:refused, %__MODULE__{type: :version_mismatch}}

          [1, _anyVersionNumber, _tstr] ->
            {:refused, %__MODULE__{type: :handshake_decode_error}}

          [2, _anyVersionNumber, _tstr] ->
            {:refused, %__MODULE__{type: :refused}}
        end

      # TODO: parse version_table
      # msgQueryReply
      {:ok, [3, version_table], ""} ->
        {:versions, version_table}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # def parse_response(full_response) do
  #   # Only works when connecting via Unix socket
  #   <<_header_todo_investigate::binary-size(8), response_payload::binary>> = full_response

  #   case CBOR.decode(response_payload) do
  #     {:ok, decoded, ""} ->
  #       {:ok, parse_cbor(decoded)}

  #     {:error, reason} ->
  #       {:error, "Error decoding CBOR: #{reason}"}
  #   end
  # end

  # defp parse_cbor([1, version_number, [network_magic, query] = node_to_client_version_data]) do
  #   with true <- is_valid_version_number(version_number),
  #        true <- is_valid_version_data(node_to_client_version_data) do
  #     {
  #       :ok,
  #       %__MODULE__{
  #         type: :msg_accept_version,
  #         version_number: version_number,
  #         network_magic: network_magic,
  #         query: query
  #       }
  #     }
  #   else
  #     _ ->
  #       {:error, :invalid_data}
  #   end
  # end

  # # msgRefuse
  # defp parse_cbor([2, refuseReason]) do
  #   case refuseReason do
  #     # TODO: return accepted versions
  #     [0, _version_number_binary] ->
  #       {:error, %__MODULE__{type: :version_mismatch}}

  #     [1, _anyVersionNumber, _tstr] ->
  #       {:error, %__MODULE__{type: :handshake_decode_error}}

  #     [2, _anyVersionNumber, _tstr] ->
  #       {:error, %__MODULE__{type: :refused}}
  #   end
  # end

  # defp parse_cbor(_), do: {:error, :unsupported_message_type}

  # # Validates version number according to CDDL definition (32783 or 32784)
  # @version_numbers [32783, 32784]
  # defp is_valid_version_number(version_number) do
  #   version_number in @version_numbers
  # end

  # # Check if the node to client version data matches expected format
  # defp is_valid_version_data([network_magic, query]) do
  #   is_integer(network_magic) and is_boolean(query)
  # end

  # defp is_valid_version_data(_), do: false
end
