<div {!! $attributes !!}>
    <div class="card-header d-flex justify-content-between align-items-start pb-0">
        <div>
            @if($icon)
            <div class="avatar bg-rgba-{{ $style }} p-50 m-0">
                <div class="avatar-content">
                    <i class="{{ $icon }} text-{{ $style }} font-medium-5"></i>
                </div>
            </div>
            @endif

            @if($title)
                <h4 class="card-title mb-1">{!! $title !!}</h4>
            @endif

            <div class="metric-header">{!! $header !!}</div>
        </div>

        @if (! empty($subTitle))
            <span class="btn btn-sm bg-light shadow-0 p-0">
                {{ $subTitle }}
            </span>
        @endif

        @if(! empty($dropdown))
        <div class="dropdown chart-dropdown">
            <button class="btn btn-sm btn-light shadow-0 dropdown-toggle p-0 waves-effect" data-toggle="dropdown">
                {{ current($dropdown) }}
            </button>
            <div class="dropdown-menu dropdown-menu-right">
                @foreach($dropdown as $key => $value)
                <li class="dropdown-item"><a href="javascript:void(0)" class="select-option" data-option="{{ $key }}">{{ $value }}</a></li>
                @endforeach
            </div>
        </div>
        @endif

        @if(! empty($betweenDateOption))
            <div class="filter-input col-sm-{{ $betweenDateOption['width'] ?? 12 }}"  style="">
                <div class="form-group d-flex justify-items-center">
                    <div class="input-group input-group-sm">
                        <input autocomplete="off" type="text" class="form-control" id="{{$cardId}}-filter-start" placeholder="{{$betweenDateOption['label'] ?? ''}}" value="{{$betweenDateOption['default']['start'] ?? ''}}">
                        <span class="input-group-addon" style="border-left: 0; border-right: 0;">To</span>
                        <input autocomplete="off" type="text" class="form-control" id="{{$cardId}}-filter-end" placeholder="{{$betweenDateOption['label'] ?? ''}}" value="{{$betweenDateOption['default']['end'] ?? ''}}">
                    </div>
                    <button type="button" class="btn click-date-search ml-1 btn-sm" style="width: 100px;" data-start="" data-end="">搜索</button>
                </div>
            </div>
        @endif


    </div>

    <div class="metric-content">{!! $content !!}</div>
</div>

@if(! empty($betweenDateOption))
    <script require="@moment,@bootstrap-datetimepicker">
        var options = {!! admin_javascript_json($betweenDateOption['options'] ?? []) !!};

        $('#{{ $cardId }}-filter-start').datetimepicker(options);
        $('#{{ $cardId }}-filter-end').datetimepicker($.extend(options, {useCurrent: false}));
        $("#{{ $cardId }}-filter-start").on("dp.change", function (e) {
            $('#{{ $cardId }}-filter-end').data("DateTimePicker").minDate(e.date);
            $('#{{ $cardId }} .click-date-search').data('start', parseInt(e.date.valueOf() / 1000))
        });
        $("#{{ $cardId }}-filter-end").on("dp.change", function (e) {
            $('#{{ $cardId }}-filter-start').data("DateTimePicker").maxDate(e.date);
            $('#{{ $cardId }} .click-date-search').data('end', parseInt(e.date.valueOf() / 1000))
        });
    </script>
@endif

