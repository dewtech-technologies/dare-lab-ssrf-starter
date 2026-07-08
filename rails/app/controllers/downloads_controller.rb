class DownloadsController < ActionController::API
  # POST /downloads  { "file_url": "https://example.com/file.pdf" }
  #
  # Fetches the remote file through SafeFetch. When SafeFetch decides a URL is
  # unsafe it raises SafeFetch::Error, and we surface that as 422.
  def create
    result = SafeFetch.call(params[:file_url])

    render json: { ok: true, bytes: result.body.bytesize }, status: :ok
  rescue SafeFetch::Error => e
    render json: { ok: false, error: e.message }, status: :unprocessable_entity
  end
end
