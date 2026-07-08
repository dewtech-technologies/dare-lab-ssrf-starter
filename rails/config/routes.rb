Rails.application.routes.draw do
  post "/downloads", to: "downloads#create"
end
